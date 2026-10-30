'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createCsrfInboxScope } = require('../server/services/csrfInboxScope');
const canonicalize = value => String(value).trim().toLowerCase();

test('local inbox reads and verification require the authenticated owner address', async () => {
  const scope = createCsrfInboxScope({
    getProvider: () => ({ mode: 'local', mailbox: { canonicalize } }),
    resolveContext: async (id, key) => {
      assert.equal(key, String(id));
      return { mode: 'local', editable: false, email: `xss-${id}@owasp-ai-goat.invalid` };
    },
  });
  assert.equal(await scope(7, ' XSS-7@owasp-ai-goat.invalid '), 'xss-7@owasp-ai-goat.invalid');
  await assert.rejects(scope(7, 'xss-8@owasp-ai-goat.invalid'), { code: 'CSRF_INBOX_OWNER_MISMATCH', statusCode: 403 });
  await assert.rejects(scope(8, 'xss-7@owasp-ai-goat.invalid'), { statusCode: 403 });
  await assert.rejects(scope('7', 'xss-7@owasp-ai-goat.invalid'), TypeError);
});

test('external training inbox remains editable through its configured canonicalizer', async () => {
  const scope = createCsrfInboxScope({ getProvider: () => ({ mode: 'external', mailbox: { canonicalize } }),
    resolveContext: async () => { throw new Error('local owner resolver must not constrain external inbox'); } });
  assert.equal(await scope(7, ' TRAINING@sharklasers.com '), 'training@sharklasers.com');
});

test('missing provider mode and inconsistent local context cannot authorize mail access', async () => {
  for (const context of [{}, { mode: 'external', email: 'xss-7@owasp-ai-goat.invalid' },
    { mode: 'local', editable: true, email: 'xss-7@owasp-ai-goat.invalid' }]) {
    const scope = createCsrfInboxScope({ getProvider: () => ({ mode: 'local', mailbox: { canonicalize } }),
      resolveContext: async () => context });
    await assert.rejects(scope(7, 'xss-7@owasp-ai-goat.invalid'), { statusCode: 403 });
  }
  await assert.rejects(createCsrfInboxScope({ getProvider: () => ({ mailbox: { canonicalize } }),
    resolveContext: async () => ({}) })(7, 'xss-7@owasp-ai-goat.invalid'), /configuration unavailable/);
});
