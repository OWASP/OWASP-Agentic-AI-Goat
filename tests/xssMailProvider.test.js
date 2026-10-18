'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssMailProviderSelector, LOCAL_SENDER } = require('../server/services/xssMailProvider');

function adapter() {
  return { sendEmail() {}, fetchEmails() {}, fetchEmail() {}, close() {},
    getStatus: () => ({ targetEmail: 'Sender@Example.COM' }) };
}

test('mailpit is the lazy default and derives an immutable inbox from platform identity', async () => {
  let created = 0;
  const local = adapter();
  const selector = createXssMailProviderSelector({
    readProvider: () => undefined,
    createLocal: () => { created += 1; return local; },
    getGmail: () => { throw new Error('gmail loaded eagerly'); },
    getExternalMailbox: () => { throw new Error('external mailbox loaded eagerly'); },
    getEmailStore: () => { throw new Error('identity store loaded for local mode'); },
  });
  assert.equal(created, 0);
  const selected = selector.getXssMailProvider();
  assert.equal(created, 1);
  assert.equal(selector.getXssMailProvider(), selected);
  assert.deepEqual(selected, { provider: 'mailpit', mode: 'local', transport: local, mailbox: local });
  const context = await selector.resolveXssMailContext(42, '42');
  assert.deepEqual(context, { email: 'xss-42@dvaia.invalid', mode: 'local', provider: 'mailpit',
    editable: false, sender: LOCAL_SENDER });
  assert.equal(Object.isFrozen(context), true);
});

test('explicit gmail resolves the configured external inbox and status sender lazily', async () => {
  const gmail = adapter();
  const mailbox = adapter();
  const calls = [];
  const selector = createXssMailProviderSelector({
    readProvider: () => ' GMAIL ',
    createLocal: () => { throw new Error('local adapter loaded'); },
    getGmail: () => { calls.push('gmail'); return gmail; },
    getExternalMailbox: () => { calls.push('mailbox'); return mailbox; },
    getEmailStore: () => ({ getConfiguredEmail: async owner => {
      calls.push(`store:${owner}`);
      return ' Learner@SharkLasers.COM ';
    } }),
  });
  assert.deepEqual(calls, []);
  const context = await selector.resolveXssMailContext(7, 'owner-7');
  assert.deepEqual(calls, ['gmail', 'mailbox', 'store:owner-7']);
  assert.deepEqual(context, { email: 'learner@sharklasers.com', mode: 'external', provider: 'gmail',
    editable: true, sender: 'sender@example.com' });
  const selected = selector.getXssMailProvider();
  assert.equal(selected.transport, gmail);
  assert.equal(selected.mailbox, mailbox);
});

test('unknown providers and invalid platform identities fail without loading adapters or stores', async () => {
  let touched = false;
  const dependencies = {
    createLocal: () => { touched = true; return adapter(); },
    getGmail: () => { touched = true; return adapter(); },
    getExternalMailbox: () => { touched = true; return adapter(); },
    getEmailStore: () => { touched = true; return { getConfiguredEmail: async () => '' }; },
  };
  const unknown = createXssMailProviderSelector({ ...dependencies, readProvider: () => 'smtp' });
  assert.throws(() => unknown.getXssMailProvider(), /Unsupported XSS_MAIL_PROVIDER/);
  assert.equal(touched, false);

  const local = createXssMailProviderSelector({ ...dependencies, readProvider: () => 'mailpit' });
  for (const [userId, userKey] of [[0, '0'], ['7', '7'], [Number.MAX_SAFE_INTEGER + 1, '7'], [7, ''], [7, 'bad\nowner']]) {
    await assert.rejects(() => local.resolveXssMailContext(userId, userKey), /platform user ID|owner key/);
  }
  assert.equal(touched, false);
});

test('provider selection is fixed after lazy initialization', () => {
  let provider = 'mailpit';
  const selector = createXssMailProviderSelector({
    readProvider: () => provider,
    createLocal: adapter,
    getGmail: adapter,
    getExternalMailbox: adapter,
  });
  selector.getXssMailProvider();
  provider = 'gmail';
  assert.throws(() => selector.getXssMailProvider(), /cannot change after initialization/);
});

test('close before selection is lazy, idempotent, and permanently revokes the selector', async () => {
  let created = 0;
  const selector = createXssMailProviderSelector({
    readProvider: () => 'mailpit',
    createLocal: () => { created += 1; return adapter(); },
  });
  const first = selector.close();
  const second = selector.close();
  assert.equal(first, second);
  await first;
  assert.equal(created, 0, 'closing an unused selector must not initialize its transport');
  assert.throws(() => selector.getXssMailProvider(), /selector is closed/);
  await assert.rejects(() => selector.resolveXssMailContext(4, '4'), /selector is closed/);
});

test('close drains an initialized transport exactly once and rejects reuse while close is pending', async () => {
  let closeCalls = 0;
  let release;
  const held = new Promise(resolve => { release = resolve; });
  const local = { ...adapter(), close: async () => { closeCalls += 1; await held; } };
  const selector = createXssMailProviderSelector({ readProvider: () => 'mailpit', createLocal: () => local });
  selector.getXssMailProvider();
  const closing = selector.close();
  assert.throws(() => selector.getXssMailProvider(), /selector is closed/);
  await assert.rejects(() => selector.resolveXssMailContext(4, '4'), /selector is closed/);
  assert.equal(selector.close(), closing);
  release();
  await closing;
  await selector.close();
  assert.equal(closeCalls, 1);
});
