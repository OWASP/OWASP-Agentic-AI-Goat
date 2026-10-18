const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm09-misinformation
 * @teaches OWASP-LLM:LLM09
 * @location agent-host/agents/price-advisor/tools/index.js
 * find_deals fabricates competitor prices — the tool announces grounded=false.
 */
test('llm09-misinformation: find_deals returns ungrounded competitor prices', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    const { findDeals } = require(path.join(REPO, 'agent-host/agents/price-advisor/tools/index.js'));
    const r = await findDeals({ category: 'Electronics' });
    assert.equal(r.grounded, false);
    assert.ok(r.deals.length > 0);
    for (const d of r.deals) assert.ok(d.competitor_price !== undefined, 'each deal claims a competitor price');
  } finally {
  }
});
