const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability file-upload-svg-xss
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/uploads/tools/index.js
 *
 * Attacker uploads an SVG containing <script>alert(1)</script>. The file is
 * written to disk with its original extension; MIME is trusted; and the
 * download tool + static route later serve it as image/svg+xml with inline
 * disposition — browser executes the script.
 */
test('file-upload-svg-xss: SVG with <script> is written verbatim and served inline (intentional)', async t => {
  const s = await seedShop();
  t.after(async () => { await s.close(); });
  const a = await seedAgents();
  t.after(async () => { await a.close(); });
  purgeToolCaches();
  const written = [];
  try {
    const uploads = require(path.join(REPO, 'agent-host/agents/uploads/tools/index.js'));
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><script>alert('xss')</script></svg>`;
    const up = uploads.upload_avatar({
      user_id: 42,
      file_bytes_base64: Buffer.from(svg).toString('base64'),
      filename: 'evil.svg',
      mime: 'image/svg+xml',
    });
    assert.equal(up.ok, true);
    written.push(up.written_path);
    // The exact <script> tag survives on disk
    const readBack = fs.readFileSync(up.written_path, 'utf8');
    assert.match(readBack, /<script>alert\('xss'\)<\/script>/);
    // Download surfaces svg mime + utf8 body
    const rel = path.relative(uploads.UPLOAD_ROOT, up.written_path);
    const d = uploads.download({ id: rel });
    assert.equal(d.mime, 'image/svg+xml');
    assert.match(d.body_utf8 || '', /<script>alert/);
  } finally {
    for (const p of written) { try { fs.unlinkSync(p); } catch {} }
  }
});
