const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const http = require('node:http');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability ssrf-listing-import
 * @teaches OWASP-Web:A10
 * @location agent-host/agents/listing/tools/import_bulk.js
 * The importer fetches whatever URL the merchant supplies with no allow-list,
 * so an internal-network host (127.0.0.1:<any-port>) is reachable.
 */
test('ssrf-listing-import: importer fetches 127.0.0.1 URL merchant supplies', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    // Simulate an internal metadata service the merchant should never reach.
    const server = http.createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify([{ name: 'INTERNAL-METADATA', description: 'internal-svc-secret', price: 0 }]));
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const { import_bulk } = require(path.join(REPO, 'agent-host/agents/listing/tools/import_bulk.js'));
    const r = await import_bulk({ json_url: `http://127.0.0.1:${port}/latest/meta-data` });
    await new Promise(resolve => server.close(resolve));

    assert.equal(r.ok, true);
    assert.equal(r.inserted.length, 1, 'internal-metadata rows landed in products table');
  } finally { await s.close(); }
});
