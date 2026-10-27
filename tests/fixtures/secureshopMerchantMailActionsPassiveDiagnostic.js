'use strict';

// Test-only observation. Never retain the system prompt, message, tool body, or address.
const { createHash } = require('node:crypto');
const assert = require('node:assert/strict');

const digest = value => createHash('sha256').update(value).digest('hex');
const positive = value => Number.isSafeInteger(value) && value > 0;

function createMerchantMailPassiveDiagnostic() {
  let decision = null;
  return Object.freeze({
    observe(input, result) {
      const sends = (result?.tool_uses || []).filter(call => call?.name === 'email.send_reply');
      if (!sends.length) return;
      assert.equal(decision, null, 'at most one reply decision may be observed');
      assert.equal(sends.length, 1, 'one reply decision is required');
      assert.equal(typeof input?.system, 'string');
      const marker = '\nServer-owned mail reply task context (mail-reply-task-context-v1).';
      assert.ok(input.system.includes(marker), 'trusted reply context is required');
      const contextJson = input.system.slice(input.system.lastIndexOf('\n') + 1);
      const context = JSON.parse(contextJson);
      assert.deepEqual(Object.keys(context).sort(), ['actingPersona', 'replyTarget', 'version']);
      assert.equal(context.version, 1);
      assert.deepEqual(Object.keys(context.replyTarget || {}).sort(),
        ['originalSenderEmail', 'originalSenderId', 'sourceMessageId', 'threadId']);
      assert.ok(positive(context.replyTarget.originalSenderId));
      assert.ok(positive(context.replyTarget.sourceMessageId));
      assert.ok(positive(context.replyTarget.threadId));
      assert.ok(positive(sends[0]?.args?.recipientId));
      assert.equal(result.provider, 'ollama');
      assert.equal(result.model, 'llama3.1:8b');
      assert.equal(result.mocked, false);
      assert.notEqual(result.fallback, true);
      decision = Object.freeze({ version: 1,
        originalSenderId: context.replyTarget.originalSenderId,
        providerInputSystemSha256: digest(input.system),
        trustedContextSha256: digest(contextJson),
        selectedRecipientId: sends[0].args.recipientId });
    },
    complete(savedSend, expectedOriginalSenderId) {
      assert.ok(decision, 'actual reply decision must precede a saved receipt');
      assert.ok(positive(expectedOriginalSenderId));
      assert.equal(decision.originalSenderId, expectedOriginalSenderId);
      assert.ok(positive(savedSend?.recipientId));
      assert.equal(savedSend.recipientId, decision.selectedRecipientId,
        'the retained effect must match the original model choice');
      return Object.freeze({ ...decision, persistedRecipientId: savedSend.recipientId });
    },
  });
}

module.exports = { createMerchantMailPassiveDiagnostic };
