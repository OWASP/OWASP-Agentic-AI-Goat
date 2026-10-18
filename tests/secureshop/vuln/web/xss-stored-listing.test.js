const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability xss-stored-listing
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/listing/tools/create.js
 * Merchant-supplied HTML persists to products.description_html and
 * downstream is rendered via dangerouslySetInnerHTML in Product.jsx.
 */
test('xss-stored-listing: create persists <img onerror> verbatim', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { create } = require(path.join(REPO, 'agent-host/agents/listing/tools/create.js'));
    const payload = `<img src=x onerror="alert('pwn')">`;
    const r = await create({ title: 'Stored XSS', description: payload, price: 5.99 });
    const { rows: [row] } = await s.query(
      `SELECT description_html FROM secureshop.products WHERE id = $1`, [r.product_id],
    );
    assert.match(row.description_html, /<img src=x onerror=/);
  } finally {
    await s.close();
  }
});
