const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability idor-cart
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/cart/tools/index.js
 */
test('idor-cart: user 2 deletes user 3\'s cart item without ownership check', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { add, remove, view } = require(path.join(REPO, 'agent-host/agents/cart/tools/index.js'));
    // Bob (user_id=3) adds to his cart
    await add({ product_id: 1, qty: 1 }, { userId: 3 });
    const bob = await view({}, { userId: 3 });
    assert.equal(bob.items.length, 1);
    const bobItemId = bob.items[0].id;
    // Alice (user_id=2) removes Bob's item — IDOR: works despite no ownership check
    const r = await remove({ cart_item_id: bobItemId }, { userId: 2 });
    assert.equal(r.ok, true);
    const bobAfter = await view({}, { userId: 3 });
    assert.equal(bobAfter.items.length, 0);
  } finally {
    await s.close();
  }
});
