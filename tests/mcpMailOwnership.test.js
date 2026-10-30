'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const mailClient = require('../server/services/mcp/mailClient');

function response(messages, ok = true) {
  return { ok, async json() { return { messages }; } };
}

function summary({ ID, MessageID, to = 'shared@example.test', subject = 'report' }) {
  return {
    ID, MessageID, To: [{ Address: to }], From: { Address: 'sender@example.test' },
    Subject: subject, Snippet: subject, Created: '2026-09-13T00:00:00Z',
  };
}

test('empty SMTP receipt set checks health without reading the shared mailbox', async () => {
  const urls = [];
  const result = await mailClient.listMessagesBySmtpIds([], {
    fetcher: async url => { urls.push(url); return response([]); },
  });
  assert.deepEqual(result, { ok: true, messages: [] });
  assert.deepEqual(urls.map(url => new URL(url).pathname), ['/api/v1/info']);
});

test('only successful session send receipts become Mailpit lookup keys', () => {
  assert.deepEqual(mailClient.deliveredSmtpMessageIds([
    { delivered: true, messageId: '<owned@local>' },
    { delivered: false, messageId: '<failed@local>' },
    { delivered: true },
    null,
  ]), ['owned@local']);
});

test('more than 200 receipts produce at most 20 lookups for the newest unique owned IDs', async () => {
  const reports = Array.from({ length: 205 }, (_, index) => ({
    delivered: true, messageId: `<owner-${index}@local>`,
  }));
  reports.push({ delivered: true, messageId: '<owner-204@local>' });
  const ownedIds = mailClient.deliveredSmtpMessageIds(reports);
  assert.equal(ownedIds.length, mailClient._internals.MAX_EXFIL_MAIL_RECEIPTS);
  assert.deepEqual(ownedIds, Array.from({ length: 20 }, (_, offset) => `owner-${204 - offset}@local`));

  const queries = [];
  const result = await mailClient.listMessagesBySmtpIds(ownedIds, {
    fetcher: async url => {
      const smtpId = new URL(url).searchParams.get('query').slice('message-id:'.length);
      queries.push(smtpId);
      return response([summary({ ID: `mailpit-${smtpId}`, MessageID: `<${smtpId}>` })]);
    },
  });
  assert.equal(queries.length, 20);
  assert.deepEqual(queries, ownedIds);
  assert.equal(result.messages.length, 20);
});

test('SMTP Message-ID receipts separate owners who use the same recipient', async () => {
  const requested = [];
  const result = await mailClient.listMessagesBySmtpIds(['<owner-a@local>'], {
    fetcher: async url => {
      requested.push(new URL(url).searchParams.get('query'));
      return response([
        summary({ ID: 'mailpit-foreign', MessageID: '<owner-b@local>', subject: 'foreign' }),
        summary({ ID: 'mailpit-owned', MessageID: '<owner-a@local>', subject: 'owned' }),
      ]);
    },
  });
  assert.deepEqual(requested, ['message-id:owner-a@local']);
  assert.equal(result.ok, true);
  assert.deepEqual(result.messages.map(message => message.subject), ['owned']);
});

test('targeted search finds an older owned message without relying on Mailpit latest pagination', async () => {
  const urls = [];
  const result = await mailClient.listMessagesBySmtpIds(['old-owned@local'], {
    fetcher: async url => {
      urls.push(url);
      return response([summary({ ID: 'old-mailpit-id', MessageID: 'old-owned@local', subject: 'old owned' })]);
    },
  });
  assert.equal(result.messages[0].subject, 'old owned');
  assert.equal(new URL(urls[0]).pathname, '/api/v1/search');
  assert.equal(urls[0].includes('/api/v1/messages?limit=20'), false);
});

test('Mailpit database ID never substitutes for the recorded SMTP Message-ID', async () => {
  const result = await mailClient.listMessagesBySmtpIds(['smtp-receipt@local'], {
    fetcher: async () => response([
      summary({ ID: 'smtp-receipt@local', MessageID: 'different@local', subject: 'internal ID collision' }),
      summary({ ID: 'mailpit-internal-id', MessageID: '<smtp-receipt@local>', subject: 'exact SMTP receipt' }),
    ]),
  });
  assert.deepEqual(result.messages.map(message => ({ id: message.id, messageId: message.messageId })), [
    { id: 'mailpit-internal-id', messageId: '<smtp-receipt@local>' },
  ]);
});

test('a failed targeted lookup returns no partial mailbox evidence', async () => {
  let calls = 0;
  const result = await mailClient.listMessagesBySmtpIds(['one@local', 'two@local'], {
    fetcher: async () => (++calls === 1
      ? response([summary({ ID: 'one', MessageID: 'one@local' })])
      : response([], false)),
  });
  assert.deepEqual(result, { ok: false, messages: [] });
});

test('reset deletion uses exact owned receipts and never sends an empty delete request', async () => {
  const calls = [];
  const fetcher = async (url, opts = {}) => {
    calls.push({ url, opts });
    if (opts.method === 'DELETE') return { ok: true };
    return response([
      summary({ ID: 'owned-db-id', MessageID: 'owned@smtp' }),
      summary({ ID: 'other-db-id', MessageID: 'other@smtp' }),
      summary({ ID: 'owned-db-id', MessageID: 'owned@smtp' }),
    ]);
  };
  assert.deepEqual(await mailClient.deleteMessagesBySmtpIds(['<owned@smtp>', 'owned@smtp'], { fetcher }), { ok: true, deleted: 1 });
  assert.deepEqual(JSON.parse(calls.find(call => call.opts.method === 'DELETE').opts.body), { IDs: ['owned-db-id'] });
  calls.length = 0;
  assert.deepEqual(await mailClient.deleteMessagesBySmtpIds([], { fetcher }), { ok: true, deleted: 0 });
  assert.equal(calls.length, 0);
  assert.deepEqual(await mailClient.deleteMessagesBySmtpIds(['missing@smtp'], { fetcher }), { ok: true, deleted: 0 });
  assert.ok(calls.every(call => call.opts.method !== 'DELETE'));
});

test('partial cleanup returns only unfinished receipts so retries make progress', async () => {
  const deleted = [];
  const result = await mailClient.deleteMessagesBySmtpIds(['a@smtp', 'b@smtp'], {
    timeoutMs: 1000,
    fetcher: async (url, options = {}, timeout) => {
      assert.ok(timeout > 0 && timeout <= 1000);
      if (options.method === 'DELETE') { deleted.push(...JSON.parse(options.body).IDs); return { ok: true }; }
      if (new URL(url).searchParams.get('query') === 'message-id:b@smtp') throw Error('timeout');
      return response([summary({ ID: 'a-id', MessageID: 'a@smtp' })]);
    },
  });
  assert.deepEqual(deleted, ['a-id']);
  assert.deepEqual(result, { ok: false, deleted: 1, remainingMessageIds: ['b@smtp'] });
});

test('durable SMTP adapter rejects a non-server-assigned Message-ID before transport', async () => {
  await assert.rejects(mailClient.sendOwnedReport({ to: 'owned@example.test', subject: 'subject', body: 'body',
    messageId: 'learner-selected@example.test' }), /Canonical server-assigned MCP Message-ID is required/);
});

const readbackMessageId = 'mcp-123e4567-e89b-42d3-a456-426614174000@owasp-ai-goat.local';
const readbackInput = Object.freeze({ messageId: readbackMessageId,
  to: 'mcp-audit-0123456789abcdefabcd@owasp-ai-goat.invalid',
  subject: 'RE: Integration diagnostic',
  body: 'Ticket escalation report\n\n--- attached internal data ---\nDB_PASSWORD=TRAINING_ONLY' });
function readbackSummary(overrides = {}) {
  return { ID: 'mailpit-owned-row', MessageID: `<${readbackMessageId}>`, ...overrides };
}
function readbackDetail(overrides = {}) {
  return { ID: 'mailpit-owned-row', MessageID: readbackMessageId,
    To: [{ Address: readbackInput.to, Name: '' }], Subject: readbackInput.subject,
    Text: `${readbackInput.body.replace(/\n/g, '\r\n')}\r\n`, ...overrides };
}
function jsonResponse(value, ok = true) { return { ok, async json() { return value; } }; }

test('full Mailpit readback binds exact Message-ID, recipient, subject and decoded text without returning payload', async () => {
  const calls = [];
  const result = await mailClient.verifyMessageReadback(readbackInput, { fetcher: async (url, options, timeout) => {
    calls.push({ url, options, timeout });
    return calls.length === 1
      ? jsonResponse({ messages_count: 1, messages: [readbackSummary()] })
      : jsonResponse(readbackDetail());
  } });
  assert.equal(result.ok, true); assert.equal(result.status, 'verified');
  assert.equal(mailClient.isTrustedMessageReadback(result.receipt), true);
  assert.equal(result.receipt.messageId, readbackMessageId);
  assert.equal(result.receipt.transportTerminalNewline, true);
  assert.equal(result.receipt.submittedBodySha256,
    crypto.createHash('sha256').update(readbackInput.body).digest('hex'));
  assert.equal(result.receipt.normalizedObservedTextSha256,
    crypto.createHash('sha256').update(`${readbackInput.body}\n`).digest('hex'));
  assert.equal(JSON.stringify(result).includes(readbackInput.body), false);
  assert.equal(JSON.stringify(result).includes(readbackInput.subject), false);
  assert.equal(JSON.stringify(result).includes(readbackInput.to), false);
  assert.deepEqual(calls.map(call => call.options), [{ redirect: 'error' }, { redirect: 'error' }]);
  assert.deepEqual(calls.map(call => call.timeout), [3000, 3000]);
  assert.equal(new URL(calls[0].url).searchParams.get('query'), `message-id:${readbackMessageId}`);
  assert.equal(new URL(calls[0].url).searchParams.get('limit'), '2');
  assert.match(calls[1].url, /\/api\/v1\/message\/mailpit-owned-row$/);
});

test('readback distinguishes exact decoded bytes from the one permitted SMTP terminal newline', async () => {
  const fetchFor = detail => async url => url.includes('/api/v1/search')
    ? jsonResponse({ messages_count: 1, messages: [readbackSummary()] }) : jsonResponse(detail);
  const exact = await mailClient.verifyMessageReadback(readbackInput,
    { fetcher: fetchFor(readbackDetail({ Text: readbackInput.body })) });
  assert.equal(exact.ok, true); assert.equal(exact.receipt.transportTerminalNewline, false);
  for (const text of [
    `${readbackInput.body}\n\n`, `${readbackInput.body} changed`,
    readbackInput.body.replace('TRAINING_ONLY', 'DIFFERENT'), `${readbackInput.body}\rchanged`,
  ]) {
    assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput,
      { fetcher: fetchFor(readbackDetail({ Text: text })) }), { ok: false, status: 'mismatch' });
  }
});

test('readback rejects absent or duplicate Message-ID search results before detail lookup', async () => {
  let calls = 0;
  assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () => {
    calls++; return jsonResponse({ messages_count: 0, messages: [] });
  } }), { ok: false, status: 'not_found' });
  assert.equal(calls, 1);
  assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () =>
    jsonResponse({ messages_count: 0, messages: [readbackSummary()] }) }),
  { ok: false, status: 'unavailable' }, 'a contradictory empty count is not authoritative absence');
  calls = 0;
  assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () => {
    calls++; return jsonResponse({ messages_count: 2,
      messages: [readbackSummary(), readbackSummary({ ID: 'mailpit-duplicate-row' })] });
  } }), { ok: false, status: 'ambiguous' });
  assert.equal(calls, 1);
  assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () =>
    jsonResponse({ messages_count: 2, messages: [readbackSummary()] }) }),
  { ok: false, status: 'ambiguous' }, 'count detects duplicates beyond returned search rows');
});

test('readback rejects reserved, traversal and escaped Mailpit row IDs before detail fetch', async () => {
  for (const id of ['latest', 'LATEST', '..', '../foreign', 'row/foreign', 'row%2Fforeign']) {
    let calls = 0;
    const result = await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () => {
      calls++; return jsonResponse({ messages_count: 1, messages: [readbackSummary({ ID: id })] });
    } });
    assert.deepEqual(result, { ok: false, status: 'mismatch' });
    assert.equal(calls, 1, `${id} must not reach the detail endpoint`);
  }
});

test('readback rejects summary and detail identity, recipient, subject and payload mismatches', async () => {
  const searchMismatch = await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () =>
    jsonResponse({ messages_count: 1, messages: [readbackSummary({ MessageID: 'foreign@owasp-ai-goat.local' })] }) });
  assert.deepEqual(searchMismatch, { ok: false, status: 'mismatch' });
  const cases = [
    readbackDetail({ ID: 'different-row' }),
    readbackDetail({ MessageID: 'foreign@owasp-ai-goat.local' }),
    readbackDetail({ To: [{ Address: 'different@owasp-ai-goat.invalid' }] }),
    readbackDetail({ To: [{ Address: readbackInput.to }, { Address: 'copy@owasp-ai-goat.invalid' }] }),
    readbackDetail({ Subject: `${readbackInput.subject} changed` }),
    readbackDetail({ Text: 'unrelated full body' }),
  ];
  for (const detail of cases) {
    let calls = 0;
    const result = await mailClient.verifyMessageReadback(readbackInput, { fetcher: async () => {
      calls++; return calls === 1
        ? jsonResponse({ messages_count: 1, messages: [readbackSummary()] }) : jsonResponse(detail);
    } });
    assert.deepEqual(result, { ok: false, status: 'mismatch' });
    assert.equal(mailClient.isTrustedMessageReadback(result.receipt), false);
  }
});

test('readback rejects malformed authority before fetch and fails closed on API or redirect errors', async () => {
  let calls = 0;
  await assert.rejects(mailClient.verifyMessageReadback({ ...readbackInput, messageId: '<' + readbackMessageId + '>' },
    { fetcher: async () => { calls++; } }), /Canonical owned mail readback values/);
  await assert.rejects(mailClient.verifyMessageReadback({ ...readbackInput, extra: true },
    { fetcher: async () => { calls++; } }), /Exact owned mail readback input/);
  assert.equal(calls, 0);
  assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput,
    { fetcher: async () => { throw Error('redirect rejected'); } }),
  { ok: false, status: 'unavailable' });
  assert.deepEqual(await mailClient.verifyMessageReadback(readbackInput,
    { fetcher: async () => jsonResponse({}, false) }),
  { ok: false, status: 'unavailable' });
  assert.equal(mailClient.isTrustedMessageReadback({}), false);
});
