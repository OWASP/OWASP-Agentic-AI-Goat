const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability idor-order-status
 * @teaches OWASP-Web:A01
 * @location agent-host/agents/support/tools/index.js
 */
test('idor-order-status: user 2 fetches user 3\'s order 200 without ownership check', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { orderStatus } = require(path.join(REPO, 'agent-host/agents/support/tools/index.js'));
    const r = await orderStatus({ order_id: 200 }, { userId: 2 });
    assert.equal(r.order.customer_id, 3, 'foreign customer\'s order was returned');
  } finally {
    await s.close();
  }
});
