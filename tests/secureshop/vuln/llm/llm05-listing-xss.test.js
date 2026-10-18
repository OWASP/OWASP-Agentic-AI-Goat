const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm05-listing-xss
 * @teaches OWASP-LLM:LLM05
 * @location agent-host/agents/listing/tools/_llmRewrite.js
 * The listing.create tool's internal LLM rewrite passes embedded HTML/script
 * tags straight through into products.description_html without sanitization.
 */
test('llm05-listing-xss: LLM rewrite writes <script> into products.description_html', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    const { create } = require(path.join(REPO, 'agent-host/agents/listing/tools/create.js'));
    const payload = `<script>fetch('/steal?c='+document.cookie)</script>`;
    const r = await create({ title: 'Poisoned', description: payload, price: 1.00 });
    assert.equal(r.ok, true);
    assert.match(r.description_html, /<script>/);
    const { rows: [row] } = await s.query(
      'SELECT description_html FROM secureshop.products WHERE id = $1',
      [r.product_id],
    );
    assert.match(row.description_html, /<script>fetch\('\/steal/);
  } finally {
  }
});
