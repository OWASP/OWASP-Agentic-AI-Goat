'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../server/services/secureshopExternalMailContract');
const operationId = '2c837430-324e-4c55-a673-38727d8b208b';
const scopeKey = 'a'.repeat(64);
const preview = () => C.makeExternalMailPreview({
  operationId, sender: 'test@gmail.com', recipient: 'learner@sharklasers.com',
});

test('recipient canonicalization permits only a single bare SharkLasers address', () => {
  assert.equal(C.normalizeExternalRecipient('Learner+test@SHARKLASERS.COM'), 'learner+test@sharklasers.com');
  for (const value of [null, '', ' user@sharklasers.com', 'user@sharklasers.com ',
    'user@sharklasers.com\r\nBcc:target@example.test', 'User <user@sharklasers.com>',
    'user@sharklasers.com,target@sharklasers.com', 'user@sub.sharklasers.com',
    'user@sharklasers.com.invalid', 'user@@sharklasers.com', 'usér@sharklasers.com',
    '.user@sharklasers.com', 'user.@sharklasers.com', 'us..er@sharklasers.com',
    `${'a'.repeat(65)}@sharklasers.com`, 'user@localhost']) {
    assert.throws(() => C.normalizeExternalRecipient(value), { code: 'INVALID_ARGUMENT' });
  }
});

test('preview is fixed synthetic plaintext and rejects all caller-added mail fields', () => {
  const canonical = preview();
  assert.ok(Object.isFrozen(canonical));
  assert.equal(canonical.subject, 'SecureShop synthetic delivery test');
  assert.match(canonical.text, new RegExp(operationId));
  assert.deepEqual(C.validateExternalMailPreview(canonical), canonical);
  for (const [field, value] of Object.entries({
    html: '<script>untrusted()</script>', cc: 'other@sharklasers.com', bcc: 'other@sharklasers.com',
    attachments: [], headers: {}, subject: 'arbitrary', text: 'arbitrary',
    sender: 'test@example.test', operationId: 'not-a-uuid',
  })) {
    assert.throws(() => C.validateExternalMailPreview({ ...canonical, [field]: value }),
      { code: 'INVALID_ARGUMENT' });
  }
});

test('review digest binds operation, recipient, sender and opaque authority scope', () => {
  const canonical = preview();
  const digest = C.externalMailRequestSha256(canonical, scopeKey);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.equal(C.externalMailRequestSha256(preview(), scopeKey), digest);
  for (const changed of [
    C.makeExternalMailPreview({ ...canonical, recipient: 'other@sharklasers.com' }),
    C.makeExternalMailPreview({ ...canonical, sender: 'other@gmail.com' }),
    C.makeExternalMailPreview({ ...canonical, operationId: '2c837430-324e-4c55-a673-38727d8b208c' }),
  ]) assert.notEqual(C.externalMailRequestSha256(changed, scopeKey), digest);
  assert.notEqual(C.externalMailRequestSha256(canonical, 'b'.repeat(64)), digest);
  assert.throws(() => C.externalMailRequestSha256(canonical, 'caller-scope'), { code: 'INVALID_ARGUMENT' });
});

test('prepare and confirm accept closed schemas without caller identity or content', () => {
  const draft = { version: 1, operationId, recipient: 'Learner@sharklasers.com', scopeKey };
  assert.equal(C.prepareInput(draft).recipient, 'learner@sharklasers.com');
  const confirmation = { version: 1, operationId, requestSha256: C.externalMailRequestSha256(preview(), scopeKey) };
  assert.deepEqual(C.confirmationInput(confirmation), confirmation);
  for (const extra of ['principalId', 'sender', 'text', 'headers', 'scopeKey']) {
    assert.throws(() => C.confirmationInput({ ...confirmation, [extra]: 'untrusted' }),
      { code: 'INVALID_ARGUMENT' });
  }
  for (const extra of ['principalId', 'sender', 'text', 'headers']) {
    assert.throws(() => C.prepareInput({ ...draft, [extra]: 'untrusted' }), { code: 'INVALID_ARGUMENT' });
  }
  for (const invalid of [{ ...draft, version: 2 }, { ...draft, operationId: operationId.toUpperCase() },
    { ...draft, scopeKey: scopeKey.toUpperCase() }, [], Object.assign(Object.create(null), draft)]) {
    assert.throws(() => C.prepareInput(invalid), { code: 'INVALID_ARGUMENT' });
  }
});
