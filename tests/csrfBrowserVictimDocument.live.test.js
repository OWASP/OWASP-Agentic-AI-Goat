'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { createCsrfBrowserExecutor, VICTIM_DOCUMENT_BOUNDARY } = require('../server/services/csrfBrowserExecutor');
const enabled = process.env.CSRF_BROWSER_NATIVE === '1';
const victim = 'http://victim.csrf.invalid';
const path = '/api/workshop/csrf/agent-action';

test('owned Chrome executes a victim-origin gadget with exact HttpOnly cookie and one observed response', { skip: !enabled, timeout: 30000 }, async t => {
  const executor = createCsrfBrowserExecutor({ attackerOrigin: 'http://attacker.csrf.invalid',
    victimOrigin: victim, documentOrigin: 'victim' });
  t.after(() => executor.close());
  const cookie = { name: 'owned_victim', value: randomBytes(24).toString('hex') };
  const marker = randomBytes(12).toString('hex');
  // A relative action URL establishes the document's actual origin. The second
  // attempted request must not dispatch another owned effect.
  const html = `<img src="/missing" onerror="fetch('${path}?tab=xss',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:'${marker}',visibleCookie:document.cookie})});fetch('${path}?tab=xss',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})">`;
  let calls = 0;
  const result = await executor.execute({ html, victimCookie: cookie, onRequest: async observed => {
    calls++;
    assert.equal(observed.frameOrigin, victim);
    assert.equal(observed.url, `${victim}${path}?tab=xss`);
    assert.equal(observed.cookiePresent, true);
    assert.deepEqual(JSON.parse(observed.postData), { message: marker, visibleCookie: '' });
    return { status: 200, contentType: 'application/json', body: '{"effect":"owned-handler-receipt"}' };
  } });
  assert.equal(calls, 1);
  assert.equal(result.responseObserved, true);
  assert.equal(result.responseStatus, 200);
  assert.equal(result.boundary, VICTIM_DOCUMENT_BOUNDARY);
  assert(!JSON.stringify(result).includes(cookie.value));
  assert(result.blockedRequests.some(row => row.url === `${victim}/missing`));
});
