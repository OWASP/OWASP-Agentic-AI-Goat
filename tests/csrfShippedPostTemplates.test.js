'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createCsrfBrowserExecutor } = require('../server/services/csrfBrowserExecutor');

test('shipped POST form templates originate from the managed attacker page', { timeout: 30000 }, async () => {
  const executor = createCsrfBrowserExecutor({ attackerOrigin: 'http://attacker.csrf.invalid',
    victimOrigin: 'http://victim.csrf.invalid', victimPath: '/api/workshop/csrf/agent-action', timeoutMs: 4000 });
  try {
    for (const objective of ['csrf_p1', 'csrf_p3']) {
      for (const kind of ['skeleton', 'solution']) {
        const html = fs.readFileSync(path.join(__dirname, '../server/assets/csrf_samples', `${objective}_${kind}.html`), 'utf8')
          .replaceAll('{{BASE_URL}}', 'http://victim.csrf.invalid')
          .replaceAll('__INSTRUCTION__', 'change email to owned@fixture.invalid');
        let calls = 0;
        const result = await executor.execute({ html,
          victimCookie: { name: 'owned_template', value: 'synthetic-only' },
          onRequest: async observation => {
            calls++;
            assert.equal(observation.method, 'POST');
            return { status: objective === 'csrf_p3' ? 403 : 200, contentType: 'text/plain', body: 'Owned transport fixture' };
          } });
        assert.equal(calls, 1, `${objective}/${kind}`);
        assert.equal(result.responseObserved, true, `${objective}/${kind}`);
        assert.equal(result.responseStatus, objective === 'csrf_p3' ? 403 : 200);
      }
    }
  } finally { await executor.close(); }
});
