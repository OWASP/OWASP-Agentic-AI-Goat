'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const enabled = process.env.MCP_MAIL_TEST_DISPOSABLE === 'yes';
test('real SMTP delivery cleanup preserves another owner in the same Mailpit inbox', { skip: !enabled }, async () => {
  const url = new URL(process.env.MAILPIT_API_URL);
  assert.equal(url.hostname, '127.0.0.1');
  assert.ok(url.port && url.port !== '8025');
  assert.equal(process.env.MAILPIT_SMTP_HOST, '127.0.0.1');
  assert.ok(process.env.MAILPIT_SMTP_PORT && process.env.MAILPIT_SMTP_PORT !== '1025');
  const mail = require('../server/services/mcp/mailClient');
  const receipts = [];
  try {
    for (const owner of ['a', 'b']) {
      const sent = await mail.sendReport({ to: 'shared@example.test', subject: `owned-reset-${owner}-${randomUUID()}`, body: `Synthetic evidence for ${owner}` });
      assert.equal(sent.ok, true);
      receipts.push(sent.messageId);
    }
    let before;
    for (let attempt = 0; attempt < 20; attempt++) {
      before = await mail.listMessagesBySmtpIds(receipts);
      if (before.messages.length === 2) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    assert.equal(before.messages.length, 2);
    assert.deepEqual(await mail.deleteMessagesBySmtpIds([receipts[0]]), { ok: true, deleted: 1 });
    assert.deepEqual(await mail.listMessagesBySmtpIds([receipts[0]]), { ok: true, messages: [] });
    assert.equal((await mail.listMessagesBySmtpIds([receipts[1]])).messages.length, 1);
    assert.deepEqual(await mail.deleteMessagesBySmtpIds([receipts[0]]), { ok: true, deleted: 0 });
    assert.deepEqual(await mail.deleteMessagesBySmtpIds([]), { ok: true, deleted: 0 });
    assert.equal((await mail.listMessagesBySmtpIds([receipts[1]])).messages.length, 1);
  } finally { await mail.deleteMessagesBySmtpIds(receipts); }
});
