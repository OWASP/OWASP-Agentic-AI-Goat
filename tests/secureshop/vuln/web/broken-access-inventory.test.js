const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability broken-access-inventory
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/inventory/tools/index.js
 * set_stock does not verify products.retailer_id === ctx.userId, so any
 * merchant can overwrite stock on another merchant's SKU.
 */
test('broken-access-inventory: set_stock overwrites another merchant\'s SKU', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    // Give product 2 a specific owner (retailer_id=3) and known stock
    await s.query(`UPDATE secureshop.products SET retailer_id = $1, stock_quantity = $2 WHERE id = $3`, [3, 25, 2]);

    const { set_stock } = require(path.join(REPO, 'agent-host/agents/inventory/tools/index.js'));
    // Attacker userId = 2 (not the owner of product 2 whose retailer_id = 3)
    const r = await set_stock({ product_id: 2, qty: 9999 }, { userId: 2 });
    assert.equal(r.ok, true);

    const { rows: [row] } = await s.query(
      `SELECT stock_quantity, retailer_id FROM secureshop.products WHERE id = $1`, [2],
    );
    assert.equal(row.stock_quantity, 9999, 'stock rewritten across owner boundary');
    assert.equal(row.retailer_id, 3, 'retailer id unchanged — still Bob');
  } finally { await s.close(); }
});
