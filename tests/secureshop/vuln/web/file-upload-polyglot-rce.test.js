const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability file-upload-polyglot-rce
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/uploads/tools/index.js
 *
 * Stable legacy ID: this test checks crafted-byte acceptance and MIME only.
 * The abbreviated GIF-signature fixture is not proven to decode as an image,
 * run in a browser, or execute on the server. Those require separate proofs.
 */
test('file-upload-polyglot-rce (legacy ID): GIF signature and JS bytes are preserved, not executed', async t => {
  const s = await seedShop();
  t.after(async () => { await s.close(); });
  const a = await seedAgents();
  t.after(async () => { await a.close(); });
  purgeToolCaches();
  const written = [];
  try {
    const uploads = require(path.join(REPO, 'agent-host/agents/uploads/tools/index.js'));
    // This is a deliberately abbreviated byte fixture, not a valid-image
    // decoder or browser/server execution qualification.
    const polyglot = Buffer.concat([
      Buffer.from('GIF89a', 'ascii'),
      Buffer.from('/*'),
      // Placeholder body: this test makes no valid GIF decoding claim.
      Buffer.from([0x00, 0x00, 0x00, 0x00]),
      Buffer.from('*/=1;window.p0lyglot=1;alert(1)//', 'ascii'),
    ]);
    const up = uploads.upload_product_image({
      product_id: 5,
      file_bytes_base64: polyglot.toString('base64'),
      filename: 'polyglot.gif',
      mime: 'image/gif',
    });
    assert.equal(up.ok, true);
    written.push(up.written_path);
    const readBack = fs.readFileSync(up.written_path);
    assert.equal(readBack.slice(0, 6).toString('ascii'), 'GIF89a', 'GIF magic preserved');
    assert.match(readBack.toString('ascii'), /window\.p0lyglot=1/, 'JS tail preserved');
    // Download reflects image/gif MIME (trusted from extension)
    const rel = path.relative(uploads.UPLOAD_ROOT, up.written_path);
    const d = uploads.download({ id: rel });
    assert.equal(d.mime, 'image/gif');
  } finally {
    for (const p of written) { try { fs.unlinkSync(p); } catch {} }
  }
});
