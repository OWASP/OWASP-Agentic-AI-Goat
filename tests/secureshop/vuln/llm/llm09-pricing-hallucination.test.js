const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { seedShop, purgeToolCaches } = require('../_fixture.js');

const REPO = path.resolve(__dirname, '../../../..');

/**
 * @intentional-vulnerability llm09-pricing-hallucination
 * @teaches OWASP-LLM:LLM09
 * @location agent-host/agents/pricing-strategy/tools/index.js
 * run_pricing_experiment invents elasticity, projected_units_lift, and
 * confidence numbers with no grounding source. The disclaimer flags it
 * but nothing in the tool prevents an LLM from citing the numbers as fact.
 */
test('llm09-pricing-hallucination: run_pricing_experiment fabricates ungrounded projections', async (t) => {
  const s = await seedShop();
  t.after(() => s.close());
  purgeToolCaches();
  try {
    const { run_pricing_experiment } = require(path.join(REPO, 'agent-host/agents/pricing-strategy/tools/index.js'));
    const r = await run_pricing_experiment({ product_id: 1, strategy: 'undercut' });
    assert.equal(r.ok, true);
    assert.equal(r.grounded, false, 'grounded must be false');
    assert.ok(r.projections.elasticity > 0, 'elasticity fabricated');
    assert.ok(r.projections.confidence > 0.5, 'confidence dressed up');
    assert.ok(typeof r.projections.projected_revenue_delta === 'number');
    assert.match(r.disclaimer, /unverified|no grounding/i);
  } finally {
  }
});
