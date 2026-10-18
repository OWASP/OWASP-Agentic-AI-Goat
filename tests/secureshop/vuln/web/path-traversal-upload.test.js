const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability path-traversal-upload
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/uploads/tools/index.js
 *
 * `_cleanFilename` does a single-pass strip of "../". The "....//" payload
 * defeats it: after strip, one "../" remains. `path.resolve()` then honors
 * that traversal and the file escapes the upload root.
 */
test('path-traversal-upload: "....//" escapes the upload root', async t => {
  const s = await seedShop();
  t.after(async () => { await s.close(); });
  const a = await seedAgents();
  t.after(async () => { await a.close(); });
  purgeToolCaches();
  const written = [];
  try {
    const uploads = require(path.join(REPO, 'agent-host/agents/uploads/tools/index.js'));
    const rawFilename = `....//escaped_${Date.now()}.txt`;
    const cleaned = uploads._cleanFilename(rawFilename);
    // After single-pass strip of "../", "....//x" leaves "../x"
    assert.match(cleaned, /^\.\.\//, `single-pass strip should leave "../" prefix, got ${cleaned}`);
    const up = uploads.upload_avatar({
      user_id: 99,
      file_bytes_base64: Buffer.from('escape').toString('base64'),
      filename: rawFilename,
      mime: 'text/plain',
    });
    assert.equal(up.ok, true);
    assert.equal(up.is_traversal, true, 'tool must flag this as a traversal write');
    written.push(up.written_path);
    // The written path must be OUTSIDE the scoped base directory (avatars/99/)
    const base = path.join(uploads.UPLOAD_ROOT, 'avatars', '99');
    const rel = path.relative(base, up.written_path);
    assert.ok(rel.startsWith('..') || path.isAbsolute(rel), 'written path escapes the scoped base');
  } finally {
    for (const p of written) { try { fs.unlinkSync(p); } catch {} }
  }
});
