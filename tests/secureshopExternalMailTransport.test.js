'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { makeExternalMailPreview } = require('../server/services/secureshopExternalMailContract');
const { createExternalMailTransport, readExternalMailConfiguration, SMTP_HOST, SMTP_PORT } =
  require('../server/services/secureshopExternalMailTransport');

const OPERATION_ID = '123e4567-e89b-42d3-a456-426614174000';
const config = Object.freeze({ enabled: true, sender: 'sender@gmail.com', appPassword: 'abcdefghijklmnop' });
const preview = recipient => makeExternalMailPreview({ operationId: OPERATION_ID,
  sender: config.sender, recipient });

function harness({ result, send, close, create } = {}) {
  const calls = { create: [], send: [], close: 0, verify: 0 };
  const transport = {
    async sendMail(mail) {
      calls.send.push(mail);
      return send ? send(mail) : result || { messageId: '<accepted@fixture.invalid>',
        accepted: [mail.to], rejected: [] };
    },
    async verify() { calls.verify += 1; },
    async close() { calls.close += 1; await close?.(); },
  };
  return { calls, adapter: createExternalMailTransport({ config,
    createTransport(options) { calls.create.push(options); return create ? create(transport, options) : transport; } }) };
}

test('is disabled unless the literal private opt-in and both dedicated credentials exist', async () => {
  assert.deepEqual(readExternalMailConfiguration({}), { enabled: false, sender: null, appPassword: null });
  assert.equal(readExternalMailConfiguration({ SS_EXTERNAL_MAIL_ENABLED: '1' }).enabled, false);
  const unavailable = createExternalMailTransport({ config: readExternalMailConfiguration({}),
    createTransport() { throw Error('must not allocate SMTP'); } });
  assert.equal(unavailable.isAvailable(), false);
  await assert.rejects(unavailable.send(preview('one@sharklasers.com')),
    { code: 'EXTERNAL_MAIL_UNAVAILABLE' });
  assert.deepEqual(readExternalMailConfiguration({ SS_EXTERNAL_MAIL_ENABLED: 'true',
    SS_EXTERNAL_MAIL_GMAIL_USER: 'sender@gmail.com', SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD: 'abcd efgh ijkl mnop' }),
  { enabled: true, sender: 'sender@gmail.com', appPassword: 'abcdefghijklmnop' });
});

test('sends only the fixed server preview through verified TLS on Gmail implicit TLS', async () => {
  const { adapter, calls } = harness();
  const result = await adapter.send(preview('Learner+one@sharklasers.com'));
  assert.equal(calls.create.length, 1);
  assert.deepEqual({ ...calls.create[0], connectionTimeout: undefined, greetingTimeout: undefined,
    socketTimeout: undefined }, { host: SMTP_HOST, port: SMTP_PORT, secure: true, requireTLS: true,
    auth: { user: 'sender@gmail.com', pass: 'abcdefghijklmnop' },
    tls: { servername: SMTP_HOST, rejectUnauthorized: true },
    connectionTimeout: undefined, greetingTimeout: undefined, socketTimeout: undefined });
  for (const timeout of ['connectionTimeout', 'greetingTimeout', 'socketTimeout']) {
    assert.ok(Number.isSafeInteger(calls.create[0][timeout]) && calls.create[0][timeout] > 0
      && calls.create[0][timeout] <= 20000, `${timeout} stays within the aggregate deadline`);
  }
  assert.equal(calls.verify, 0, 'dispatch performs no separate readiness connection');
  assert.deepEqual(calls.send, [{ from: 'sender@gmail.com', to: 'learner+one@sharklasers.com',
    subject: 'SecureShop synthetic delivery test', text: preview('learner+one@sharklasers.com').text }]);
  assert.deepEqual(result, { smtpAccepted: true, deliveryConfirmed: false,
    messageId: '<accepted@fixture.invalid>', accepted: ['learner+one@sharklasers.com'], rejected: [] });
  assert.equal(calls.close, 1);
});

test('rejects noncanonical or non-template previews before SMTP allocation', async () => {
  const { adapter, calls } = harness();
  for (const candidate of [
    { ...preview('one@sharklasers.com'), recipient: 'one@sharklasers.com, two@sharklasers.com' },
    { ...preview('one@sharklasers.com'), recipient: 'One <one@sharklasers.com>' },
    { ...preview('one@sharklasers.com'), recipient: 'one@sharklasers.com\r\nBcc:x@y.invalid' },
    { ...preview('one@sharklasers.com'), recipient: 'one@sharklasers.com.evil' },
    { ...preview('one@sharklasers.com'), subject: 'caller supplied subject' },
    { ...preview('one@sharklasers.com'), text: 'caller supplied text' },
    { ...preview('one@sharklasers.com'), html: '<b>not allowed</b>' },
    { ...preview('one@sharklasers.com'), sender: 'other@gmail.com' },
  ]) await assert.rejects(adapter.send(candidate), { code: 'EXTERNAL_MAIL_INVALID_REQUEST' });
  assert.equal(calls.create.length, 0);
  assert.equal(calls.send.length, 0);
});

test('requires exactly one accepted recipient and no rejection, then closes each attempt', async () => {
  for (const result of [
    { accepted: ['one@sharklasers.com'], rejected: [] },
    { messageId: '<id>', accepted: [], rejected: [] },
    { messageId: '<id>', accepted: ['other@sharklasers.com'], rejected: [] },
    { messageId: '<id>', accepted: ['one@sharklasers.com', 'other@sharklasers.com'], rejected: [] },
    { messageId: '<id>', accepted: ['one@sharklasers.com'], rejected: ['one@sharklasers.com'] },
    { messageId: '<id>', accepted: ['one@sharklasers.com', {}], rejected: [] },
    { messageId: '<id>', accepted: ['one@sharklasers.com'], rejected: [{}] },
    { messageId: '<id>', accepted: ['one@sharklasers.com'] },
    { messageId: '<id>', rejected: [] },
  ]) {
    const { adapter, calls } = harness({ result });
    await assert.rejects(adapter.send(preview('one@sharklasers.com')), error =>
      error.code === 'EXTERNAL_MAIL_UNKNOWN' && error.dispatchStarted === true && error.uncertain === true);
    assert.equal(calls.send.length, 1);
    assert.equal(calls.close, 1);
  }
});

test('never retries and treats a post-dispatch provider failure as unknown without exposing provider text', async () => {
  const { adapter, calls } = harness({ send: async () => { throw Error('smtp secret response recipient one@sharklasers.com'); } });
  await assert.rejects(adapter.send(preview('one@sharklasers.com')), error =>
    error.code === 'EXTERNAL_MAIL_UNKNOWN' && error.dispatchStarted === true && error.uncertain === true
      && error.message === 'External test mail unavailable');
  assert.equal(calls.send.length, 1);
  assert.equal(calls.close, 1);
});

test('aborts before dispatch or during transport construction without calling sendMail', async () => {
  const prior = new AbortController(); prior.abort();
  const noStart = harness();
  await assert.rejects(noStart.adapter.send(preview('one@sharklasers.com'), { signal: prior.signal }), error =>
    error.code === 'EXTERNAL_MAIL_TIMEOUT' && error.dispatchStarted === false && error.uncertain === false);
  assert.equal(noStart.calls.create.length, 0);

  const duringCreate = new AbortController();
  const raced = harness({ create(transport) { duringCreate.abort(); return transport; } });
  await assert.rejects(raced.adapter.send(preview('one@sharklasers.com'), { signal: duringCreate.signal }), error =>
    error.code === 'EXTERNAL_MAIL_TIMEOUT' && error.dispatchStarted === false && error.uncertain === false);
  assert.equal(raced.calls.create.length, 1);
  assert.equal(raced.calls.send.length, 0);
  assert.equal(raced.calls.close, 1);
});

test('closes a bounded post-dispatch timeout once and does not let close exceed its effective deadline', async () => {

  let release;
  const pending = new Promise(resolve => { release = resolve; });
  const started = harness({ send: async () => pending });
  await assert.rejects(started.adapter.send(preview('one@sharklasers.com'), { deadlineAt: Date.now() + 30 }), error =>
    error.code === 'EXTERNAL_MAIL_UNKNOWN' && error.dispatchStarted === true && error.uncertain === true);
  assert.equal(started.calls.send.length, 1);
  assert.equal(started.calls.close, 1);
  release({ messageId: '<late>', accepted: ['one@sharklasers.com'], rejected: [] });
});

test('a hanging close is invoked but cannot extend a short effective deadline', async () => {
  const never = new Promise(() => {});
  const { adapter, calls } = harness({ close: async () => never });
  const started = Date.now();
  await adapter.send(preview('one@sharklasers.com'), { deadlineAt: Date.now() + 30 });
  assert.ok(Date.now() - started < 250, 'close wait is bounded by the same effective deadline');
  assert.equal(calls.close, 1);
});

test('provider error properties are never surfaced', async () => {
  const secret = 'smtp-provider-secret-recipient@sharklasers.com';
  const { adapter } = harness({ send: async () => {
    const error = Object.assign(new Error(secret), { response: secret, command: secret, code: 'EAUTH' });
    throw error;
  } });
  await assert.rejects(adapter.send(preview('one@sharklasers.com')), error => {
    assert.equal(error.message, 'External test mail unavailable');
    assert.equal(JSON.stringify(error), JSON.stringify({ name: 'ExternalMailTransportError',
      code: 'EXTERNAL_MAIL_UNKNOWN', dispatchStarted: true, uncertain: true }));
    assert.equal(error.stack.includes(secret), false);
    return true;
  });
});
