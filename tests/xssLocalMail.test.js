'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { createXssLocalMail } = require('../server/services/xssLocalMail');

function jsonResponse(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: init.status || 200,
    headers: { 'content-type': 'application/json; charset=utf-8', ...(init.headers || {}) },
  });
}

function mailSummary(overrides = {}) {
  return {
    ID: 'mailpit-internal-1',
    MessageID: '<smtp-receipt-1@dvaia.invalid>',
    To: [{ Address: 'xss-7@dvaia.invalid', Name: '' }],
    From: { Address: 'attacker@dvaia.invalid', Name: '' },
    Subject: 'DVAIA marker',
    Created: '2026-09-13T10:00:00Z',
    Read: false,
    ...overrides,
  };
}

function harness({ sendResult, fetcher, timeoutMs = 100 } = {}) {
  const calls = { create: 0, send: [], close: 0, fetch: [] };
  const transport = {
    async sendMail(mail) {
      calls.send.push(mail);
      return sendResult || { messageId: '<smtp-1@dvaia.invalid>', accepted: [mail.to], rejected: [] };
    },
    async close() { calls.close += 1; },
  };
  const nodemailer = {
    createTransport(options) {
      calls.create += 1;
      calls.transportOptions = options;
      return transport;
    },
  };
  const wrappedFetch = async (url, options) => {
    calls.fetch.push({ url, options });
    return fetcher ? fetcher(url, options) : jsonResponse({ messages: [] });
  };
  const adapter = createXssLocalMail({
    smtpHost: '127.0.0.1', smtpPort: 1025, apiUrl: 'http://127.0.0.1:8025/',
    nodemailer, fetcher: wrappedFetch, timeoutMs,
  });
  return { adapter, calls };
}

test('sends exact text and codec HTML and reports SMTP acceptance without claiming delivery', async () => {
  const { adapter, calls } = harness();
  const html = '<pre>&lt;img src=x onerror="window.__owned=1"&gt; &amp; exact</pre>';
  const receipt = await adapter.sendEmail('xss-7@dvaia.invalid', 'subject', 'logical & body', '7', { html });

  assert.deepEqual(calls.send, [{
    from: 'attacker@dvaia.invalid', to: 'xss-7@dvaia.invalid', subject: 'subject',
    text: 'logical & body', html,
  }]);
  assert.deepEqual(receipt, {
    success: true,
    messageId: '<smtp-1@dvaia.invalid>',
    sentTo: 'xss-7@dvaia.invalid',
    sentFrom: 'attacker@dvaia.invalid',
    subject: 'subject',
    accepted: ['xss-7@dvaia.invalid'],
    rejected: [],
    smtpAccepted: true,
    deliveryConfirmed: false,
  });
  assert.equal(adapter.getStatus().provider, 'mailpit');
  assert.equal(adapter.getStatus().targetEmail, 'attacker@dvaia.invalid');
});

test('rejects non-owned, noncanonical, list and owner-mismatched recipients before transport or API access', async () => {
  const { adapter, calls } = harness();
  const invalid = [
    'xss-7@dvaia.invalid, xss-8@dvaia.invalid',
    'xss-7@dvaia.invalid; xss-8@dvaia.invalid',
    'Learner <xss-7@dvaia.invalid>',
    'xss-7@dvaia.invalid\r\nBcc: xss-8@dvaia.invalid',
    'xss-7@@dvaia.invalid',
    'xss-07@dvaia.invalid',
    'XSS-7@dvaia.invalid',
    'xss-7@example.test',
  ];
  for (const recipient of invalid) {
    await assert.rejects(adapter.sendEmail(recipient, 's', 'b', '7'), { code: 'INVALID_RECIPIENT' });
  }
  await assert.rejects(adapter.sendEmail('xss-7@dvaia.invalid', 's', 'b', '8'), { code: 'RECIPIENT_OWNER_MISMATCH' });
  assert.equal(calls.create, 0);
  assert.equal(calls.send.length, 0);
  assert.equal(calls.fetch.length, 0);
});

test('fails closed when SMTP acceptance evidence is missing, rejected, or partial', async () => {
  for (const sendResult of [
    { accepted: ['xss-7@dvaia.invalid'], rejected: [] },
    { messageId: '<id>', accepted: [], rejected: [] },
    { messageId: '<id>', accepted: ['xss-7@dvaia.invalid'], rejected: ['other@dvaia.invalid'] },
    { messageId: '<id>', accepted: ['xss-7@dvaia.invalid', 'other@dvaia.invalid'], rejected: [] },
  ]) {
    const { adapter } = harness({ sendResult });
    await assert.rejects(adapter.sendEmail('xss-7@dvaia.invalid', 's', 'b', '7'), {
      code: 'SMTP_ACCEPTANCE_UNVERIFIED',
    });
  }
});

test('searches exact recipient, rejects unrelated To rows, and applies sender filtering only when requested', async () => {
  const exact = mailSummary();
  const alternateSender = mailSummary({ ID: 'mailpit-internal-2', MessageID: '<smtp-2>',
    From: { Address: 'other@dvaia.invalid' } });
  const wrongRecipient = mailSummary({ ID: 'mailpit-internal-3', MessageID: '<smtp-3>',
    To: [{ Address: 'xss-70@dvaia.invalid' }] });
  const multipleRecipients = mailSummary({ ID: 'mailpit-internal-4', MessageID: '<smtp-4>',
    To: [{ Address: 'xss-7@dvaia.invalid' }, { Address: 'xss-8@dvaia.invalid' }] });
  const { adapter, calls } = harness({ fetcher: async () => jsonResponse({
    messages: [exact, alternateSender, wrongRecipient, multipleRecipients],
  }) });

  const filtered = await adapter.fetchEmails('xss-7@dvaia.invalid');
  assert.deepEqual(filtered.emails.map(row => row.id), ['mailpit-internal-1']);
  const allOwned = await adapter.fetchEmails('xss-7@dvaia.invalid', false);
  assert.deepEqual(allOwned.emails.map(row => row.id), ['mailpit-internal-1', 'mailpit-internal-2']);

  const request = new URL(calls.fetch[0].url);
  assert.equal(request.pathname, '/api/v1/search');
  assert.equal(request.searchParams.get('query'), 'to:"xss-7@dvaia.invalid"');
  assert.equal(request.searchParams.get('limit'), '50');
  assert.equal(calls.fetch[0].options.method, 'GET');
  assert.equal(calls.fetch[0].options.redirect, 'error');
  assert.equal(calls.fetch[0].options.credentials, 'omit');
});

test('fetches exact Mailpit detail while preserving HTML bytes and distinct SMTP/internal IDs', async () => {
  const html = '<pre data-proof="&amp;">&lt;svg/onload=alert(1)&gt;</pre>';
  const detail = mailSummary({ Text: 'logical <body> & exact', HTML: html });
  const { adapter, calls } = harness({ fetcher: async () => jsonResponse(detail) });
  const result = await adapter.fetchEmail('xss-7@dvaia.invalid', 'mailpit-internal-1');

  assert.equal(result.success, true);
  assert.equal(result.email.id, 'mailpit-internal-1');
  assert.equal(result.email.messageId, '<smtp-receipt-1@dvaia.invalid>');
  assert.equal(result.email.body, 'logical <body> & exact');
  assert.equal(result.email.htmlBody, html);
  assert.equal(new URL(calls.fetch[0].url).pathname, '/api/v1/message/mailpit-internal-1');
});

test('detail retrieval fails closed on recipient, sender, internal ID, or SMTP ID mismatch', async () => {
  const cases = [
    mailSummary({ To: [{ Address: 'xss-8@dvaia.invalid' }] }),
    mailSummary({ From: { Address: 'other@dvaia.invalid' } }),
    mailSummary({ ID: 'different-internal-id' }),
    mailSummary({ MessageID: 'mailpit-internal-1' }),
  ];
  for (const detail of cases) {
    const { adapter } = harness({ fetcher: async () => jsonResponse(detail) });
    await assert.rejects(adapter.fetchEmail('xss-7@dvaia.invalid', 'mailpit-internal-1'), error =>
      ['MAILPIT_MESSAGE_MISMATCH', 'MAILPIT_INVALID_RESPONSE'].includes(error.code));
  }
});

test('mailbox responses are bounded, JSON-only, nonredirecting, and deadline-bound', async () => {
  {
    const { adapter } = harness({ fetcher: async () => new Response('{}', {
      status: 200, headers: { 'content-type': 'text/plain' },
    }) });
    await assert.rejects(adapter.fetchEmails('xss-7@dvaia.invalid'), { code: 'MAILPIT_INVALID_RESPONSE' });
  }
  {
    const { adapter } = harness({ fetcher: async () => jsonResponse({ messages: [] }, {
      headers: { 'content-length': String(600 * 1024) },
    }) });
    await assert.rejects(adapter.fetchEmails('xss-7@dvaia.invalid'), { code: 'MAILPIT_RESPONSE_TOO_LARGE' });
  }
  {
    const redirect = jsonResponse({ messages: [] });
    Object.defineProperty(redirect, 'redirected', { value: true });
    const { adapter } = harness({ fetcher: async () => redirect });
    await assert.rejects(adapter.fetchEmails('xss-7@dvaia.invalid'), { code: 'MAILPIT_UNAVAILABLE' });
  }
  {
    let aborted = false;
    const { adapter } = harness({ timeoutMs: 15, fetcher: (_url, options) => new Promise((_resolve, reject) => {
      options.signal.addEventListener('abort', () => {
        aborted = true;
        reject(new Error('private Mailpit endpoint detail'));
      }, { once: true });
    }) });
    await assert.rejects(adapter.fetchEmails('xss-7@dvaia.invalid'), error => {
      assert.equal(error.code, 'MAILPIT_TIMEOUT');
      assert.doesNotMatch(error.message, /private|endpoint/i);
      return true;
    });
    assert.equal(aborted, true);
  }
});

test('close is idempotent, closes a created transport, and revokes later use', async () => {
  const { adapter, calls } = harness();
  await adapter.sendEmail('xss-7@dvaia.invalid', 's', 'b', '7');
  await adapter.close();
  await adapter.close();
  assert.equal(calls.close, 1);
  await assert.rejects(adapter.fetchEmails('xss-7@dvaia.invalid'), { code: 'MAIL_ADAPTER_CLOSED' });
  await assert.rejects(adapter.sendEmail('xss-7@dvaia.invalid', 's', 'b', '7'), { code: 'MAIL_ADAPTER_CLOSED' });
});
